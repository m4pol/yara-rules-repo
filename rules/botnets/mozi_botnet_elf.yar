rule Mozi_Botnet_ELF_Packed {
        meta:
                description = "Use to detect packed Mozi botnet."
                author = "Phatcharadol Thangplub"
                date = "14-08-2023"
                update = "21-02-2024"

        strings:
                $s1 = "C9necti"
                $s2 = "M7c.xml" 
                $s3 = "?!ctrlt/De"
                $s4 = "mdebug._i32"
                $s5 = "DEATH*"
                $s6 = { 50 4f 53 54 20 2f 47 70 6f 6e 46 6f 72 6d 2f 64 69 61 67 ?? ?? ?? } //Mozi POST exploitation.
                $s7 = { 68 74 74 bf fd f6 ff 70 3a 2f 2f 25 73 3a 25 64 2f 4d 6f ?? ?? ?? } //Pre-Config of Mozi Hosting Address.
 
                $upx1 = "$Info: This file is packed with the UPX executable packer" nocase
                $upx2 = "UPX!" nocase
                $upx3 = { ?? 2f 70 72 6f 63 2f 73 65 6c 66 2f 65 78 65 ?? } //Part of UPX.

        condition:
                uint32(0) == 0x464C457F and filesize < 250KB and 3 of ($s*) and 2 of ($upx*)
}

rule Mozi_Botnet_ELF_Unpacked {
        meta:
                description = "Use to detect unpacked Mozi botnet."
                author = "Phatcharadol Thangplub"
                date = "14-08-2023"
                update = "21-02-2024"
                unpack_tool = "https://github.com/kn0wl3dge/mozitools"

        strings:
                $s1 = "This node doesn't accept announces" nocase
                $s2 = "[set]" nocase
                $s3 = "[cnc]" nocase
                $s4 = "[idp]" nocase
                $s5 = "[cpu]" nocase
                $s6 = "linuxshell" nocase
                $s7 = "#user" nocase
                $s8 = "http://%s:%d"
                $s9 = "!Login"
                $s10 = { 6b 69 6c 6c 61 6c 6c 20 2d 39 20 ?? ?? ?? } //Part of Mozi infection command.
                $s11 = { ?? 4d 6f 7a 69 ?? ?? } //Mozi botnet identify.

                $variant1 = "%08X%08X%08X%08X%08X%08X" fullword ascii
                $variant2 = "%19s%lx%lx%X%d%d%d%lx%d%d%d" fullword ascii
                $variant3 = "1(765$`j4p(dmn'b75e-gjk=-9c44`e-gjk(86>5%)zfhc<c,a57s)ali*~bne>4%)ziw?lt,a57s)ali*ah,iw?7$g`lj&6!g*aht,oe?7?:-656)370+0$mh" fullword ascii
                
        condition:
                uint32(0) == 0x464C457F and filesize < 400KB and (
                        ($s1 or ($s2 and $s3 and $s4 and $s5)) or 1 of ($s6, $s7, $s8) and
                        ($s9 and $s10 and $s11) or any of ($variant*)
                )
}
