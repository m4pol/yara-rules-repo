rule Mal_LNX_Mozi_Botnet_ELF {
        meta:
                description = "Use to detect Mozi botnet."
                author = "Phatcharadol Thangplub"
                date = "10-04-2024"

        strings:
                $s1 = "%08X%08X%08X%08X%08X%08X"
                $s2 = "%19s%lx%lx%X%d%d%d%lx%d%d%d"
                $s3 = "1(765$`j4p(dmn'b75e-gjk=-9c44`e-gjk(86>5%)zfhc<c,a57s)ali*~bne>4%)ziw?lt,a57s)ali*ah,iw?7$g`lj&6!g*aht,oe?7?:-656)370+0$mh"
                $s4 = "GET /Mozi"
                $s5 = "killall -9 telnetd utelnetd scfgmgr"
                $s6 = "acsMozi"

                /*
                        Related path binding.
                */
                $hex1 = { 30 40 2d e9 ?? c? 9f e5 2c d0 4d e2 0c e0 a0 e1 0f 00 b? e8 
                        04 50 8d e2 05 c0 a0 e1 0f 00 a? e8 0f 00 b? e8 0f 00 a? e8 
                        [2] 9? e5 [2] 8? e5 00 40 a0 e3 } //ARM
                
                /*
                        Infection line argument.
                */
                $hex2 = { 0e 00 54 e1 ?? c? 9f e5 ?? 4? 9f e5 01 c0 a0 01 8e 21 95 e7 [2] 9f e5 } //ARM

        condition:
                uint32(0) == 0x464C457F and filesize <= 400KB and (all of ($s*) or all of ($hex*))
}