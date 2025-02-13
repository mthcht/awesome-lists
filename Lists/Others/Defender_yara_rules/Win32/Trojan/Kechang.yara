rule Trojan_Win32_Kechang_A_2147741213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kechang.A!dha"
        threat_id = "2147741213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kechang"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\Temp\\acrtay.exe" wide //weight: 1
        $x_1_2 = "%s\\temp\\tempef2" wide //weight: 1
        $x_1_3 = "%s\\Temp\\d2fme.tmp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kechang_B_2147741254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kechang.B!dha"
        threat_id = "2147741254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kechang"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hkcu\\software\\microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v IEHardenIENoWarn" ascii //weight: 1
        $x_1_2 = "hkcu\\software\\microsoft\\Internet Explorer\\PhishingFilter\" /v ShownVerifyBalloon" ascii //weight: 1
        $x_1_3 = "\\Temp\\d2fme.tmp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kechang_C_2147741257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kechang.C!dha"
        threat_id = "2147741257"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kechang"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\MPADVFN.DLL" wide //weight: 1
        $x_2_2 = "chart.healthcare-internet.com/index.html" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Kechang_SP_2147744360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kechang.SP!MSR"
        threat_id = "2147744360"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kechang"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg add \"HKCU\\Software\\Microsoft\\Internet Explorer\\PhishingFilter\"" ascii //weight: 1
        $x_1_2 = "\\Microsoft\\Windows\\mirrorhi" wide //weight: 1
        $x_1_3 = "\\Microsoft\\Windows\\hdiserk.exe" wide //weight: 1
        $x_1_4 = "\\Microsoft\\Windows\\pageimg.tmp" wide //weight: 1
        $x_1_5 = "halimatoudi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Kechang_SR_2147746294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kechang.SR!MSR"
        threat_id = "2147746294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kechang"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 73 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 79 [0-4] 2e 64 61 74}  //weight: 1, accuracy: Low
        $x_1_2 = {56 57 68 58 92 41 00 68 e8 f1 63 00 c7 05 e4 f1 43 00 [0-4] e8 6b 8f 00 00 83 c4 08 8d 44 24 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

