rule AsyncRAT_Backdoor_PE {
    meta:
        description = "Use to detect AsyncRAT implant."
        author = "Phatcharadol Thangplub"
        date = "12-11-2023"

    strings:
        $x1 = "Pac_ket"
        $x2 = "Po_ng"
        $x3 = "plu_gin"
        $x4 = "save_Plugin"

        $da1 = { 72 ?? ?? ?? 70 80 05 00 00 04 } //Install folder varible initialize.
        $da2 = { 28 35 00 00 06 } //Registry Persistence function call.
        $da3 = { 28 45 00 00 06 } //Anti Analysis function call.
        $da4 = { 09 72 ?? ?? ?? 70 28 3C 00 00 06 39 06 00 00 00 } //Check for anti process.
        $da5 = { 28 3D 00 00 06 } //Process Killer function call.
        $da6 = { 28 28 00 00 06 } //AMSI Bypass function call.
        $da7 = { 28 67 00 00 0A 72 ?? 13 00 70 28 1C 00 00 0A 6F 1D 00 00 0A 0? 12 0? 28 2C 00 00 06 } //Load amsi.dll, and get AmsiScanBuffer function process.

    condition:
        uint16(0) == 0x5A4D and (any of ($x*) or 3 of ($da*))
}
