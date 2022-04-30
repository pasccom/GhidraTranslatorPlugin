REPOSITORY DESCRIPTION
----------------------
This repository contains a plugin for Ghidra reverse engineering suite which allows to translate strings. The translation is written as an comment after the original string. It will be useful when reverse engineering a program written in an unknown language.

FEATURES
--------
Currently, the implementation is very simple: Only one `*.mo` file is supported. The file is selected the first time the plugin is called. The only way to change the file is to close the project and reopen it.

INSTALLATION
------------
To build the plugin, invoke the following command
```
gradle -PGHIDRA_INSTALL_DIR=<Absolute path to Ghidra>
```
from the plugin root folder.

To install the plugin, go to *File > Install Extensions...* (in Ghidra first window), click on the green `+` icon in the top-right corner of the extension dialog and select the plugin `*.zip` file which is in `dist/` folder in the plugin root folder.

Subsequently, you should see a dialog, which proposes to configure the plugin when you open the "Code browser" tool. You should configure the plugin, which is not activated by default. You can always configure the plugin from the plugin dialog (*File > Configure...* in "Code browser" tool).

PLANNED DEVELOPMENTS
--------------------
Here are some ideas I plan to implement later:
  - Use the built-in translation support (from Ghidra official plugin *TranslatorStringPlugin*)
  - Support for other translation file formats (such as Qt `*.qm` files)
  - Support for other translation sources (for instance `translate.google.com`)
  - Per file/project translation file persistence 

LICENSING INFORMATION
---------------------
GhidraTranslatorPlugin is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

GhidraTranslatorPlugin is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a [copy of the GNU General Public License](LICENSE)
along with GhidraTranslatorPlugin. If not, see http://www.gnu.org/licenses/