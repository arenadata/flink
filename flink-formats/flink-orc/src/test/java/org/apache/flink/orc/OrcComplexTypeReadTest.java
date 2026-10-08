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

package org.apache.flink.orc;

import org.apache.flink.core.fs.FileInputSplit;
import org.apache.flink.core.fs.Path;
import org.apache.flink.table.api.DataTypes;
import org.apache.flink.table.data.ArrayData;
import org.apache.flink.table.data.MapData;
import org.apache.flink.table.data.RowData;
import org.apache.flink.table.types.DataType;

import org.apache.hadoop.conf.Configuration;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Reads the pre-built ORC files checked in under {@code src/test/resources} through the columnar
 * reader.
 *
 * <p>These files were produced by an external writer and cover paths that no other test reaches:
 * nested lists and maps, struct columns ({@link org.apache.flink.orc.vector.OrcRowColumnVector}),
 * repeating vectors, {@code binary} and {@code date} columns. They had been orphaned since
 * FLINK-22620 removed the row-based reader tests, which left those readers uncovered right across
 * an ORC major upgrade.
 */
class OrcComplexTypeReadTest {

    private static final int BATCH_SIZE = 7;

    @Test
    void testReadTimeTypes() throws IOException {
        // struct<time:timestamp,date:date>
        DataType[] types = new DataType[] {DataTypes.TIMESTAMP(9), DataTypes.DATE()};
        String[] names = new String[] {"time", "date"};

        int rows = 0;
        try (OrcColumnarRowSplitReader<?> reader =
                createReader("test-data-timetypes.orc", names, types, new int[] {0, 1})) {
            while (!reader.reachedEnd()) {
                RowData row = reader.nextRecord(null);
                assertThat(row.isNullAt(0)).isFalse();
                assertThat(row.isNullAt(1)).isFalse();
                // 1900-05-05 is before the epoch, so the stored date is negative
                assertThat(row.getInt(1)).isNegative();
                assertThat(row.getTimestamp(0, 9)).isNotNull();
                rows++;
            }
        }
        assertThat(rows).isEqualTo(70000);
    }

    @Test
    void testReadNestedTypesAndBinary() throws IOException {
        // struct<..., bytes1:binary, string1:string, middle:struct<list:array<struct<..>>>,
        //        list:array<struct<int1:int,string1:string>>,
        //        map:map<string,struct<int1:int,string1:string>>>
        DataType[] types =
                new DataType[] {
                    DataTypes.BOOLEAN(),
                    DataTypes.TINYINT(),
                    DataTypes.SMALLINT(),
                    DataTypes.INT(),
                    DataTypes.BIGINT(),
                    DataTypes.FLOAT(),
                    DataTypes.DOUBLE(),
                    DataTypes.BYTES(),
                    DataTypes.STRING(),
                    DataTypes.ROW(
                            DataTypes.FIELD(
                                    "list",
                                    DataTypes.ARRAY(
                                            DataTypes.ROW(
                                                    DataTypes.FIELD("int1", DataTypes.INT()),
                                                    DataTypes.FIELD(
                                                            "string1", DataTypes.STRING()))))),
                    DataTypes.ARRAY(
                            DataTypes.ROW(
                                    DataTypes.FIELD("int1", DataTypes.INT()),
                                    DataTypes.FIELD("string1", DataTypes.STRING()))),
                    DataTypes.MAP(
                            DataTypes.STRING(),
                            DataTypes.ROW(
                                    DataTypes.FIELD("int1", DataTypes.INT()),
                                    DataTypes.FIELD("string1", DataTypes.STRING())))
                };
        String[] names =
                new String[] {
                    "boolean1",
                    "byte1",
                    "short1",
                    "int1",
                    "long1",
                    "float1",
                    "double1",
                    "bytes1",
                    "string1",
                    "middle",
                    "list",
                    "map"
                };

        try (OrcColumnarRowSplitReader<?> reader =
                createReader(
                        "test-data-nested.orc", names, types, new int[] {0, 3, 7, 8, 9, 10, 11})) {
            assertThat(reader.reachedEnd()).isFalse();
            RowData row = reader.nextRecord(null);

            assertThat(row.getBoolean(0)).isFalse();
            assertThat(row.getInt(1)).isEqualTo(65536);
            // binary column - nothing else in the module reads one back
            assertThat(row.getBinary(2)).isNotNull();
            assertThat(row.getString(3).toString()).isEqualTo("hi");

            // struct column: middle.list[0].string1
            RowData middle = row.getRow(4, 1);
            ArrayData middleList = middle.getArray(0);
            assertThat(middleList.size()).isEqualTo(2);
            assertThat(middleList.getRow(0, 2).getString(1).toString()).isEqualTo("bye");

            // array of structs
            ArrayData list = row.getArray(5);
            assertThat(list.size()).isEqualTo(2);
            assertThat(list.getRow(0, 2).getInt(0)).isEqualTo(3);
            assertThat(list.getRow(1, 2).getString(1).toString()).isEqualTo("bad");

            // first row carries an empty map, the second a populated one
            assertThat(row.getMap(6).size()).isZero();

            assertThat(reader.reachedEnd()).isFalse();
            row = reader.nextRecord(null);
            MapData map = row.getMap(6);
            assertThat(map.size()).isEqualTo(2);
            assertThat(map.keyArray().getString(0).toString()).isEqualTo("chani");
            assertThat(map.valueArray().getRow(0, 2).getString(1).toString()).isEqualTo("chani");
        }
    }

    @Test
    void testReadDeeplyNestedList() throws IOException {
        // struct<mylist1:array<array<struct<mylong1:bigint>>>>
        DataType[] types =
                new DataType[] {
                    DataTypes.ARRAY(
                            DataTypes.ARRAY(
                                    DataTypes.ROW(DataTypes.FIELD("mylong1", DataTypes.BIGINT()))))
                };

        int rows = 0;
        try (OrcColumnarRowSplitReader<?> reader =
                createReader(
                        "test-data-nestedlist.orc",
                        new String[] {"mylist1"},
                        types,
                        new int[] {0})) {
            while (!reader.reachedEnd()) {
                RowData row = reader.nextRecord(null);
                ArrayData outer = row.getArray(0);
                assertThat(outer.size()).isEqualTo(1);
                ArrayData inner = outer.getArray(0);
                assertThat(inner.size()).isEqualTo(1);
                assertThat(inner.getRow(0, 1).getLong(0)).isEqualTo(rows);
                rows++;
            }
        }
        assertThat(rows).isEqualTo(100);
    }

    @Test
    void testReadRepeatingAndNullComposites() throws IOException {
        // struct<int1:int,int2:int,int3:int,record1:struct<f1:int,f2:string>,
        //        record2:struct<..>,list1:array<int>,..,map1:map<int,string>,map2:map<..>>
        DataType rec =
                DataTypes.ROW(
                        DataTypes.FIELD("f1", DataTypes.INT()),
                        DataTypes.FIELD("f2", DataTypes.STRING()));
        DataType[] types =
                new DataType[] {
                    DataTypes.INT(),
                    DataTypes.INT(),
                    DataTypes.INT(),
                    rec,
                    rec,
                    DataTypes.ARRAY(DataTypes.INT()),
                    DataTypes.ARRAY(DataTypes.INT()),
                    DataTypes.ARRAY(DataTypes.INT()),
                    DataTypes.MAP(DataTypes.INT(), DataTypes.STRING()),
                    DataTypes.MAP(DataTypes.INT(), DataTypes.STRING())
                };
        String[] names =
                new String[] {
                    "int1", "int2", "int3", "record1", "record2", "list1", "list2", "list3", "map1",
                    "map2"
                };

        int rows = 0;
        try (OrcColumnarRowSplitReader<?> reader =
                createReader(
                        "test-data-repeating.orc",
                        names,
                        types,
                        new int[] {0, 1, 3, 4, 5, 7, 8, 9})) {
            while (!reader.reachedEnd()) {
                RowData row = reader.nextRecord(null);
                // repeating non-null vector
                assertThat(row.getInt(0)).isEqualTo(42);
                // repeating all-null vector
                assertThat(row.isNullAt(1)).isTrue();
                // repeating struct, and a struct that is null for every row
                assertThat(row.getRow(2, 2).getInt(0)).isEqualTo(23);
                assertThat(row.getRow(2, 2).isNullAt(1)).isTrue();
                assertThat(row.isNullAt(3)).isTrue();
                // repeating list, and a list that is null for every row
                assertThat(row.getArray(4).size()).isEqualTo(3);
                assertThat(row.isNullAt(5)).isTrue();
                // repeating map, and a map that is null for every row
                assertThat(row.getMap(6).size()).isEqualTo(2);
                assertThat(row.isNullAt(7)).isTrue();
                rows++;
            }
        }
        assertThat(rows).isEqualTo(256);
    }

    @Test
    void testReadCompositesWithNulls() throws IOException {
        // struct<int1:int,record1:struct<f1:int,f2:string>,
        //        list1:array<array<array<struct<f1:string,f2:string>>>>,
        //        list2:array<map<string,int>>>
        DataType[] types =
                new DataType[] {
                    DataTypes.INT(),
                    DataTypes.ROW(
                            DataTypes.FIELD("f1", DataTypes.INT()),
                            DataTypes.FIELD("f2", DataTypes.STRING())),
                    DataTypes.ARRAY(
                            DataTypes.ARRAY(
                                    DataTypes.ARRAY(
                                            DataTypes.ROW(
                                                    DataTypes.FIELD("f1", DataTypes.STRING()),
                                                    DataTypes.FIELD("f2", DataTypes.STRING()))))),
                    DataTypes.ARRAY(DataTypes.MAP(DataTypes.STRING(), DataTypes.INT()))
                };
        String[] names = new String[] {"int1", "record1", "list1", "list2"};

        int rows = 0;
        int nullRecords = 0;
        int nestedLists = 0;
        int nestedMaps = 0;
        try (OrcColumnarRowSplitReader<?> reader =
                createReader(
                        "test-data-composites-with-nulls.orc",
                        names,
                        types,
                        new int[] {0, 1, 2, 3})) {
            while (!reader.reachedEnd()) {
                RowData row = reader.nextRecord(null);
                assertThat(row.getInt(0)).isEqualTo(rows);

                if (row.isNullAt(1)) {
                    nullRecords++;
                } else {
                    // the generator for this fixture is gone, so assert on structure rather than
                    // on payload: both fields of the struct have to be decodable
                    RowData record = row.getRow(1, 2);
                    assertThat(record.getArity()).isEqualTo(2);
                    assertThat(record.isNullAt(0)).isFalse();
                    assertThat(record.getString(1)).isNotNull();
                }

                if (!row.isNullAt(2)) {
                    // three levels of nesting down to a struct, with nulls at every level
                    ArrayData l1 = row.getArray(2);
                    assertThat(l1.size()).isEqualTo(4);
                    assertThat(l1.isNullAt(2)).isTrue();
                    assertThat(l1.getArray(0).getArray(0).getRow(0, 2).isNullAt(0)).isTrue();
                    nestedLists++;
                }

                if (!row.isNullAt(3)) {
                    // array of maps, the map itself carrying null keys and null values
                    ArrayData l2 = row.getArray(3);
                    assertThat(l2.size()).isEqualTo(3);
                    assertThat(l2.isNullAt(2)).isTrue();
                    MapData m = l2.getMap(0);
                    assertThat(m.size()).isEqualTo(3);
                    assertThat(m.keyArray().isNullAt(1)).isTrue();
                    assertThat(m.valueArray().isNullAt(2)).isTrue();
                    nestedMaps++;
                }
                rows++;
            }
        }
        assertThat(rows).isEqualTo(2500);
        // the fixture mixes null and populated composites in every column
        assertThat(nullRecords).isPositive();
        assertThat(nullRecords).isLessThan(rows);
        assertThat(nestedLists).isPositive();
        assertThat(nestedMaps).isPositive();
    }

    /**
     * A file that does carry real column names is matched by name, so a reader schema using
     * different names yields NULLs. {@code orc.force.positional.evolution} is the documented way
     * out; it only works because {@code OrcShimV200#readOrcConf} passes both the flag and the level
     * on to {@link org.apache.orc.Reader.Options}.
     */
    @Test
    void testReadFileWithRealColumnNames() throws IOException {
        DataType[] types = new DataType[] {DataTypes.TIMESTAMP(9), DataTypes.DATE()};
        // the file stores "time" and "date"
        String[] mismatched = new String[] {"f0", "f1"};

        try (OrcColumnarRowSplitReader<?> reader =
                createReader(
                        "test-data-timetypes.orc",
                        mismatched,
                        types,
                        new int[] {0, 1},
                        new Configuration())) {
            assertThat(reader.reachedEnd()).isFalse();
            RowData row = reader.nextRecord(null);
            assertThat(row.isNullAt(0)).isTrue();
            assertThat(row.isNullAt(1)).isTrue();
        }

        Configuration positional = new Configuration();
        positional.setBoolean("orc.force.positional.evolution", true);

        try (OrcColumnarRowSplitReader<?> reader =
                createReader(
                        "test-data-timetypes.orc",
                        mismatched,
                        types,
                        new int[] {0, 1},
                        positional)) {
            assertThat(reader.reachedEnd()).isFalse();
            RowData row = reader.nextRecord(null);
            assertThat(row.isNullAt(0)).isFalse();
            assertThat(row.isNullAt(1)).isFalse();
        }
    }

    private static OrcColumnarRowSplitReader<?> createReader(
            String resource, String[] names, DataType[] types, int[] selectedFields)
            throws IOException {
        return createReader(resource, names, types, selectedFields, new Configuration());
    }

    private static OrcColumnarRowSplitReader<?> createReader(
            String resource,
            String[] names,
            DataType[] types,
            int[] selectedFields,
            Configuration conf)
            throws IOException {
        FileInputSplit split = splitOf(resource);
        return OrcSplitReaderUtil.genPartColumnarRowReader(
                "2.3.0",
                conf,
                names,
                types,
                new HashMap<>(),
                selectedFields,
                new ArrayList<>(),
                BATCH_SIZE,
                split.getPath(),
                split.getStart(),
                split.getLength());
    }

    private static FileInputSplit splitOf(String resource) {
        URL url = OrcComplexTypeReadTest.class.getClassLoader().getResource(resource);
        assertThat(url).as("missing test resource %s", resource).isNotNull();
        File file = new File(url.getFile());
        return new FileInputSplit(0, new Path(file.toURI()), 0, file.length(), null);
    }
}
