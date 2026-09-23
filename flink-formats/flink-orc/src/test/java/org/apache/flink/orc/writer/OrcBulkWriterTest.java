/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.flink.orc.writer;

import org.apache.flink.api.common.serialization.BulkWriter;
import org.apache.flink.core.fs.Path;
import org.apache.flink.core.fs.local.LocalDataOutputStream;
import org.apache.flink.orc.data.Record;
import org.apache.flink.orc.util.OrcBulkWriterTestUtil;
import org.apache.flink.orc.vector.RecordVectorizer;
import org.apache.flink.streaming.api.functions.sink.filesystem.bucketassigners.UniqueBucketAssigner;
import org.apache.flink.streaming.api.functions.sink.filesystem.legacy.StreamingFileSink;
import org.apache.flink.streaming.api.operators.StreamSink;
import org.apache.flink.streaming.util.OneInputStreamOperatorTestHarness;

import org.apache.hadoop.conf.Configuration;
import org.apache.orc.CompressionKind;
import org.apache.orc.OrcFile;
import org.apache.orc.Reader;
import org.apache.orc.StripeInformation;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/** Unit test for the ORC BulkWriter implementation. */
class OrcBulkWriterTest {

    private final String schema = "struct<_col0:string,_col1:int>";
    private final List<Record> input =
            Arrays.asList(new Record("Shiv", 44), new Record("Jesse", 23), new Record("Walt", 50));

    /**
     * Writes and reads back a file with every compression kind supported by ORC, including ZSTD
     * which is only available since ORC 1.6.0.
     */
    @ParameterizedTest
    @EnumSource(CompressionKind.class)
    void testOrcBulkWriter(CompressionKind compressionKind, @TempDir File outDir) throws Exception {
        final Properties writerProps = new Properties();
        writerProps.setProperty("orc.compress", compressionKind.name());

        final OrcBulkWriterFactory<Record> writer =
                new OrcBulkWriterFactory<>(
                        new RecordVectorizer(schema), writerProps, new Configuration());

        StreamingFileSink<Record> sink =
                StreamingFileSink.forBulkFormat(new Path(outDir.toURI()), writer)
                        .withBucketAssigner(new UniqueBucketAssigner<>("test"))
                        .withBucketCheckInterval(10000)
                        .build();

        try (OneInputStreamOperatorTestHarness<Record, Object> testHarness =
                new OneInputStreamOperatorTestHarness<>(new StreamSink<>(sink), 1, 1, 0)) {

            testHarness.setup();
            testHarness.open();

            int time = 0;
            for (final Record record : input) {
                testHarness.processElement(record, ++time);
            }

            testHarness.snapshot(1, ++time);
            testHarness.notifyOfCompletedCheckpoint(1);

            OrcBulkWriterTestUtil.validate(outDir, input, compressionKind);
        }
    }

    /**
     * Writes a file that spans several stripes. A single-stripe file leaves most of {@link
     * PhysicalWriterImpl}'s stripe bookkeeping - the stripe counter, the per-stripe statistics
     * lists and the block padding - on their trivial path.
     *
     * <p>ORC can only close a stripe between two {@code addRowBatch} calls, and {@link
     * OrcBulkWriter} hands over a batch every {@code VectorizedRowBatch.DEFAULT_SIZE} rows, so the
     * row count has to be a multiple of that for the stripe limit to ever be reached.
     */
    @Test
    void testOrcBulkWriterWithMultipleStripes(@TempDir java.nio.file.Path tmpDir) throws Exception {
        final int rowsPerStripe = 1000;
        final int rowCount = 10 * 1024;

        final Properties writerProps = new Properties();
        writerProps.setProperty("orc.compress", CompressionKind.ZSTD.name());
        writerProps.setProperty("orc.stripe.row.count", String.valueOf(rowsPerStripe));

        final OrcBulkWriterFactory<Record> factory =
                new OrcBulkWriterFactory<>(
                        new RecordVectorizer(schema), writerProps, new Configuration());

        final File outFile = tmpDir.resolve("multi-stripe.orc").toFile();
        try (LocalDataOutputStream out = new LocalDataOutputStream(outFile)) {
            BulkWriter<Record> writer = factory.create(out);
            for (int i = 0; i < rowCount; i++) {
                writer.addElement(new Record("name-" + i, i));
            }
            writer.finish();
        }

        Reader reader =
                OrcFile.createReader(
                        new org.apache.hadoop.fs.Path(outFile.toURI()),
                        OrcFile.readerOptions(new Configuration()));

        assertThat(reader.getCompressionKind()).isSameAs(CompressionKind.ZSTD);
        assertThat(reader.getNumberOfRows()).isEqualTo(rowCount);
        assertThat(reader.getStripes()).hasSizeGreaterThan(1);
        assertThat(reader.getStripes().stream().mapToLong(StripeInformation::getNumberOfRows).sum())
                .isEqualTo(rowCount);
    }
}
