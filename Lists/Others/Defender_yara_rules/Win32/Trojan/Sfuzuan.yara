rule Trojan_Win32_Sfuzuan_A_2147712059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sfuzuan.A!bit"
        threat_id = "2147712059"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sfuzuan"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 37 62 63 36 39 66 63 33 39 37 62 33 64 34 39 64 31 39 66 30 33 62 32 64 30 38 37 64 66 63 63 61 00}  //weight: 10, accuracy: High
        $x_10_2 = {00 66 65 66 36 36 39 32 63 66 35 37 62 33 35 36 31 33 33 66 38 35 31 35 30 61 33 32 34 65 38 39 34 00}  //weight: 10, accuracy: High
        $x_10_3 = {00 32 35 39 30 35 35 33 62 37 36 35 39 31 31 66 36 36 31 30 62 36 33 63 33 36 33 30 62 36 65 61 63 00}  //weight: 10, accuracy: High
        $x_10_4 = {00 30 62 64 61 30 31 30 38 61 37 62 33 65 33 63 35 66 39 31 36 63 32 31 33 65 65 35 31 36 65 61 61 62 30 33 39 61 61 65 37 62 63 38 35 33 35 64 62 33 63 37 37 32 33 65 35 33 65 63 36 35 61 61 65 00}  //weight: 10, accuracy: High
        $x_1_5 = {6c 00 6f 00 67 00 2e 00 64 00 61 00 74 00 00 00 43 00 6f 00 64 00 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {43 72 65 61 74 65 4d 75 74 65 78 57 00 00 00 00 32 00 33 00 34 00 64 00 66 00 35 00 66 00 67 00 33 00 34 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {8d 7c 24 3c f3 a5 68 a7 00 00 00 8d 4c ?? ?? 6a 00 51 89 44 ?? ?? a4 e8 ?? ?? 00 00 83 c4 0c 8d 54 24 3c 52 68 ?? ?? ?? ?? 8b c2 50 e8 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sfuzuan_AMAB_2147852932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sfuzuan.AMAB!MTB"
        threat_id = "2147852932"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sfuzuan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "down.hjkl45678.xyz" ascii //weight: 1
        $x_1_2 = "9c8007b363c0c30578ec54b80137923ad9b144b1440e81d4" ascii //weight: 1
        $x_1_3 = "2bke7ab43c81bs6636cl655czce39bct" ascii //weight: 1
        $x_1_4 = "c82393234ea2921efe6b0ac350132ade" ascii //weight: 1
        $x_1_5 = "223.5.5.5/resolve?name=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sfuzuan_EN_2147895865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sfuzuan.EN!MTB"
        threat_id = "2147895865"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sfuzuan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c timeout /t 1 & del /Q /F" wide //weight: 1
        $x_1_2 = "1111k-1301740645.cos.ap-nanjing.myqcloud.com" wide //weight: 1
        $x_1_3 = "Host: 1111k-1301740645.cos.ap-nanjing.myqcloud.com" wide //weight: 1
        $x_1_4 = "yzzcommon.zxcv56745.xyz" wide //weight: 1
        $x_1_5 = "sc.exe start %s" wide //weight: 1
        $x_1_6 = "spi1.tyui54345.xyz" wide //weight: 1
        $x_1_7 = "spi2.tyui54345.xyz" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

