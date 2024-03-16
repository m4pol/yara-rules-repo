rule NjRAT_Backdoor_PE {
        meta:
                description = "Use to detect NjRAT implant."
                author = "Phatcharadol Thangplub"
                date = "16-03-2024"

        strings:
                $s1 = "GetKeyboardState"
                $s2 = "capGetDriverDescriptionA"
                $s3 = "CompDir"

                $hex1 = { 08 6F [4] 6F [4] 72 [4] 16 28 [4] 16 FE 01 } //Compare the process in protect function.
                $hex2 = { 7E [4] 6F [4] 6F [4] 7E [4] 17 6F [4] 7E [4] 16 6F [4] 00 } //Delete Registry Value.
                $hex3 = { 72 [4] 7E [4] 6F [4] 72 [4] 28 [4] 16 16 15 28 [4] 26 } //Execute shell commands.

        condition:
                uint16(0) == 0x5A4D and filesize >= 20KB and (any of ($s*) and any of ($hex*))
}