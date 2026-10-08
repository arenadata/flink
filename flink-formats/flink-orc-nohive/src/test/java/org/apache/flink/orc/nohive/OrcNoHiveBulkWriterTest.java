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

package org.apache.flink.orc.nohive;

import org.apache.flink.api.common.serialization.BulkWriter;
import org.apache.flink.core.fs.local.LocalDataOutputStream;
import org.apache.flink.orc.nohive.writer.NoHivePhysicalWriterImpl;
import org.apache.flink.table.data.GenericRowData;
import org.apache.flink.table.data.RowData;
import org.apache.flink.table.data.StringData;
import org.apache.flink.table.types.logical.IntType;
import org.apache.flink.table.types.logical.LogicalType;
import org.apache.flink.table.types.logical.VarCharType;

import org.apache.hadoop.conf.Configuration;
import org.apache.orc.CompressionKind;
import org.apache.orc.OrcFile;
import org.apache.orc.Reader;
import org.apache.orc.RecordReader;
import org.apache.orc.storage.ql.exec.vector.BytesColumnVector;
import org.apache.orc.storage.ql.exec.vector.LongColumnVector;
import org.apache.orc.storage.ql.exec.vector.VectorizedRowBatch;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests writing ORC files through {@link OrcNoHiveBulkWriterFactory}, which routes the file tail
 * through {@link NoHivePhysicalWriterImpl} and therefore through the protobuf classes relocated
 * inside orc-core-nohive.
 */
class OrcNoHiveBulkWriterTest {

    private static final String SCHEMA = "struct<_col0:string,_col1:int>";

    private static final LogicalType[] FIELD_TYPES =
            new LogicalType[] {new VarCharType(VarCharType.MAX_LENGTH), new IntType()};

    private static final List<RowData> INPUT = new ArrayList<>();

    static {
        INPUT.add(GenericRowData.of(StringData.fromString("Shiv"), 44));
        INPUT.add(GenericRowData.of(StringData.fromString("Jesse"), 23));
        INPUT.add(GenericRowData.of(StringData.fromString("Walt"), 50));
    }

    @ParameterizedTest
    @EnumSource(CompressionKind.class)
    void testOrcNoHiveBulkWriter(
            CompressionKind compressionKind, @TempDir java.nio.file.Path tmpDir) throws Exception {
        Configuration conf = new Configuration();
        conf.set("orc.compress", compressionKind.name());

        OrcNoHiveBulkWriterFactory factory =
                new OrcNoHiveBulkWriterFactory(conf, SCHEMA, FIELD_TYPES);

        File outFile = tmpDir.resolve("no-hive-" + compressionKind.name() + ".orc").toFile();
        try (LocalDataOutputStream out = new LocalDataOutputStream(outFile)) {
            BulkWriter<RowData> writer = factory.create(out);
            for (RowData row : INPUT) {
                writer.addElement(row);
            }
            writer.finish();
        }

        assertThat(outFile.length()).isGreaterThan(0);

        Reader reader =
                OrcFile.createReader(
                        new org.apache.hadoop.fs.Path(outFile.toURI()),
                        OrcFile.readerOptions(new Configuration()));

        assertThat(reader.getCompressionKind()).isSameAs(compressionKind);
        assertThat(reader.getNumberOfRows()).isEqualTo(INPUT.size());
        assertThat(reader.getSchema().getFieldNames()).hasSize(2);
        assertThat(readBack(reader)).isEqualTo(INPUT);
    }

    private static List<RowData> readBack(Reader reader) throws Exception {
        List<RowData> results = new ArrayList<>();
        try (RecordReader recordReader = reader.rows()) {
            VectorizedRowBatch batch = reader.getSchema().createRowBatch();
            while (recordReader.nextBatch(batch)) {
                BytesColumnVector stringVector = (BytesColumnVector) batch.cols[0];
                LongColumnVector intVector = (LongColumnVector) batch.cols[1];
                for (int r = 0; r < batch.size; r++) {
                    String name =
                            new String(
                                    stringVector.vector[r],
                                    stringVector.start[r],
                                    stringVector.length[r],
                                    StandardCharsets.UTF_8);
                    results.add(
                            GenericRowData.of(
                                    StringData.fromString(name), (int) intVector.vector[r]));
                }
            }
        }
        return results;
    }
}
