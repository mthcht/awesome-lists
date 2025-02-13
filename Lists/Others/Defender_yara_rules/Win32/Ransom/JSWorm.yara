rule Ransom_Win32_JSWorm_A_2147742172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/JSWorm.A!MTB"
        threat_id = "2147742172"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "JSWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DECRYPT.hta" ascii //weight: 1
        $x_1_2 = "JSWORM" ascii //weight: 1
        $x_1_3 = "/c reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v \"zapiska\" /d \"" ascii //weight: 1
        $x_1_4 = "/c vssadmin.exe delete shadows /all /quiet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_JSWorm_B_2147742173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/JSWorm.B!MTB"
        threat_id = "2147742173"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "JSWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JSWORM-DECRYPT.txt" ascii //weight: 1
        $x_1_2 = "All your files were encrypted!" ascii //weight: 1
        $x_1_3 = "DECRYPT.txt" ascii //weight: 1
        $x_1_4 = "ID-RANSOMWARE, IT'S JUST THE BEGINING OF SOMETHING NEW..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

