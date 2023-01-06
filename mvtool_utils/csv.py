# coding: utf-8
#
# Copyright (C) 2022 Helmar Hutschenreuter
#
# MV-Tool Utilities is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# MV-Tool Utilities is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with MV-Tool Utilities. If not, see <http://www.gnu.org/licenses/>.

import csv
from typing import Iterable, Iterator


class ExcelCSV:
    def iter_csv(self, filename, strip=True) -> Iterator[dict]:
        with open(filename, "r") as csv_file:
            # skip BOM, if present
            if csv_file.read(1) != "\ufeff":
                csv_file.seek(0)
            reader = csv.DictReader(csv_file, delimiter=";")
            for row in reader:
                if strip:
                    yield {key: value.strip() for key, value in row.items()}
                else:
                    yield row

    def read_csv(self, filename) -> list[dict]:
        return list(self.iter_csv(filename))

    def write_csv(self, filename, data: Iterable[dict]):
        with open(filename, "w", newline="", encoding="utf-8") as csv_file:
            csv_file.write("\ufeff")  # Set BOM

            writer = csv.DictWriter(csv_file, fieldnames=self.column_names, **csv.excel)
            writer.writeheader()
            writer.writerows(data)
