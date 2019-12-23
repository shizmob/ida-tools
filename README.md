# IDA scripts

Some random scripts written at various points to help with reversing.

## `export_renames.py`

When libraries obfuscate their export symbol names, you can use this script to export your fixed-up names to a JSON file
and automatically rename symbols in any target that uses said library.

* To export renames: `save_export_renames('~/my-file.json')`;
* To import renames: `load_export_renames('~/my-file.json')`;

## `auto_rename.py`

Some programs have calls to debug log functions still baked in in production, containing the name of the calling function.
You can use `auto_rename_all(dict{log_func_name: arg_idx})` to automatically rename functions that do.

# License

```
            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
                    Version 2, December 2004

 Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>

 Everyone is permitted to copy and distribute verbatim or modified
 copies of this license document, and changing it is allowed as long
 as the name is changed.

            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

  0. You just DO WHAT THE FUCK YOU WANT TO.
```
