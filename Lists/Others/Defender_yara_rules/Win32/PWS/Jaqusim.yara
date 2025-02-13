rule PWS_Win32_Jaqusim_A_2147601469_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Jaqusim.A"
        threat_id = "2147601469"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaqusim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "boundary=\"=_NextPart_2relrf" ascii //weight: 2
        $x_1_2 = "--7cf87224d2020a" ascii //weight: 1
        $x_1_3 = "Host: login.passport.com" ascii //weight: 1
        $x_2_4 = "TBSMSNChatSessionU" ascii //weight: 2
        $x_1_5 = ",sign-in=" ascii //weight: 1
        $x_1_6 = "1342177280" ascii //weight: 1
        $x_2_7 = "0x0413 winnt 5.1 i386 MSNMSGR" ascii //weight: 2
        $x_1_8 = "@hotmail.co.jp" wide //weight: 1
        $x_1_9 = "mesajcek.asp?" ascii //weight: 1
        $x_1_10 = "KATEGORI=WEBMAIL" ascii //weight: 1
        $x_1_11 = "mailcek.asp" ascii //weight: 1
        $x_1_12 = "ortamaayarcek" ascii //weight: 1
        $x_1_13 = "msngirisLoginSuccess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

