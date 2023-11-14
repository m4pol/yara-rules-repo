rule NjRAT_Backdoor_PE {
        meta:
                description = "Use to detect NjRAT implant."
                author = "Phatcharadol Thangplub"
                date = "14-11-2023"

        strings:
                $s1 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>"
                $s2 = "GetKeyboardState"
                $s3 = "capGetDriverDescriptionA"
                $s4 = "CompDir"

                $bc1 = { 72 ?? 00 00 70 80 1? 00 00 04 } //Process name, and directories varible initialize.
                $bc2 = { 72 ?B 0? 00 70 80 ?? 00 00 04 } //Path of registry persistence varible initialize.
                $bc3 = { 72 ?? 01 00 70 80 2? 00 00 04 } //The author credit varible initialize.
                $bc4 = { 72 5D 00 00 70 80 1? 00 00 04 } //C2 Port varible initialize.
                $bc5 = { 6F E5 00 00 0A 6F 31 00 00 0A 72 ?? 0D 00 70 16 28 32 00 00 0A } //Compare the process name.
                $bc6 = { 72 ?? ?? 0070 7E 1? 00 00 04 28 ?? 00 00 0A 17 6F 4? 00 00 0A 02 6F 4? 00 00 0A } //Delete Registry Value.

        condition:
                uint16(0) == 0x5A4D and (any of ($s*) or 2 of ($bc*))
}