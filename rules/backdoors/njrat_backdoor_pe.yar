rule NjRAT_Backdoor_PE {
        meta:
                description = "Use to detect NjRAT implant."
                author = "Phatcharadol Thangplub"
                date = "14-11-2023"

        strings:
                $s1 = ""

        condition:
                uint16(0) == 0x5A4D and 
}
