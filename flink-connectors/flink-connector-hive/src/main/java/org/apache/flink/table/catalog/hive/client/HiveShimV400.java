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

package org.apache.flink.table.catalog.hive.client;

import org.apache.flink.table.catalog.exceptions.CatalogException;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hive.metastore.api.FieldSchema;
import org.apache.hadoop.hive.metastore.api.Table;
import org.apache.hadoop.hive.ql.exec.FileSinkOperator;
import org.apache.hadoop.hive.ql.io.HiveOutputFormat;
import org.apache.hadoop.hive.ql.io.HivePassThroughOutputFormat;
import org.apache.hadoop.hive.serde2.Deserializer;
import org.apache.hadoop.io.Writable;
import org.apache.hadoop.mapred.JobConf;
import org.apache.hadoop.mapred.Reporter;

import java.lang.reflect.Method;
import java.util.List;
import java.util.Properties;

/** Shim for Hive version 4.0.0. */
public class HiveShimV400 extends HiveShimV313 {

    @Override
    public FileSinkOperator.RecordWriter getHiveRecordWriter(
            JobConf jobConf,
            Class outputFormatClz,
            Class<? extends Writable> outValClz,
            boolean isCompressed,
            Properties tableProps,
            Path outPath) {
        try {
            HiveOutputFormat outputFormat = (HiveOutputFormat) outputFormatClz.newInstance();
            if (!(outputFormat instanceof HiveOutputFormat)) {
                outputFormat = new HivePassThroughOutputFormat(outputFormat);
            }
            return outputFormat.getHiveRecordWriter(
                    jobConf, outPath, outValClz, isCompressed, tableProps, Reporter.NULL);
        } catch (Exception e) {
            throw new CatalogException("Failed to create Hive RecordWriter", e);
        }
    }

    public List<FieldSchema> getFieldsFromDeserializer(
            Configuration conf, Table table, boolean skipConfError) {
        try {
            Method utilMethod =
                    getHiveMetaStoreUtilsClass()
                            .getMethod(
                                    "getDeserializer",
                                    Configuration.class,
                                    Table.class,
                                    String.class,
                                    boolean.class);
            Deserializer deserializer =
                    (Deserializer) utilMethod.invoke(null, conf, table, null, skipConfError);
            utilMethod =
                    getHiveMetaStoreUtilsClass()
                            .getMethod(
                                    "getFieldsFromDeserializer",
                                    String.class,
                                    Deserializer.class,
                                    Configuration.class);
            return (List<FieldSchema>)
                    utilMethod.invoke(null, table.getTableName(), deserializer, conf);
        } catch (Exception e) {
            throw new CatalogException("Failed to get table schema from deserializer", e);
        }
    }
}
