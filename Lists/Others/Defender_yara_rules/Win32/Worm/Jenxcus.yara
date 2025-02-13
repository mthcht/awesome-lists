rule Worm_Win32_Jenxcus_A_2147683070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Jenxcus.A"
        threat_id = "2147683070"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Jenxcus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "njw0rm.pwd.resources" ascii //weight: 3
        $x_1_2 = "Download And Run" wide //weight: 1
        $x_1_3 = "Execute cmd.exe" wide //weight: 1
        $x_1_4 = "or,/c del %temp%\\*.vbs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Jenxcus_B_2147683170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Jenxcus.B"
        threat_id = "2147683170"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Jenxcus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "function post (cmd ,param)" ascii //weight: 1
        $x_1_2 = ".open \"post\",\"http://\" & host & \":\" & port &\"/\" & cmd, false" ascii //weight: 1
        $x_1_3 = ".regwrite \"HKEY_LOCAL_MACHINE\\software\\\" & split (installname,\".\")(0)  & \"\\\",  usbspreading, \"REG_SZ\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Worm_Win32_Jenxcus_N_2147686431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Jenxcus.N"
        threat_id = "2147686431"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Jenxcus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {ec 5b 8d 7c de bb 85 14 e3 13 d8 53 d3 92 70 c8 41 55 33 21 45 41 30 36 0c ff ec 9e c6 3d 06 3d 1d a8 0f 33 c0 db 7d 6f 6b 43 ca 52 af ad 00 00}  //weight: 4, accuracy: High
        $x_1_2 = {29 58 e3 b5 f7 e8 30 dc a8 11 3d 1d e7 9a b5 fc a7 08 27 17 34 bc 23 0c 57 3e 61 1a 12 c7 49 43}  //weight: 1, accuracy: High
        $x_1_3 = {10 cd 67 4d 8e 8b 41 9c fc 20 90 f9 6f b1 be 13 2f ac cb d1 4a 9c 85 9c ee 27 04 56 3a 59 7a 83}  //weight: 1, accuracy: High
        $x_1_4 = {df d5 e9 72 07 b0 7b ae 8c 2e 01 8f c5 d8 ee a6 a2 ba f9 95 34 60 65 39 69 ee e1 e1 eb d9 fe 2b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

