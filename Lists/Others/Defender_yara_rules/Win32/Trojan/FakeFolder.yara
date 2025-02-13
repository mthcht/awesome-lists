rule Trojan_Win32_FakeFolder_EM_2147845978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeFolder.EM!MTB"
        threat_id = "2147845978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeFolder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "xlsx\", \"sfslftndytmp.exe\"" ascii //weight: 10
        $x_10_2 = "xlsx\", \"xwikjylwglsf.exe\"" ascii //weight: 10
        $x_10_3 = "xls\", \"cqigrmhenwnb.exe\"" ascii //weight: 10
        $x_1_4 = "DllCall(\"shell32\\ShellExecuteW" ascii //weight: 1
        $x_1_5 = "ClClipboard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FakeFolder_DT_2147887423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeFolder.DT!MTB"
        threat_id = "2147887423"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeFolder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e5 52 1d f8 e7 ec a9 3e fd ed 6e af 84 b2 fb 39 9c 1e fb 8b 78 1d ef ed e6 b4 7d f3 b3 74 ed b1 89 db 22 eb 5a b5 c5 1d 7e 91 88 d0 4b ac cd 28 3b c1 b2 3e eb 03 f8 ec 84 c0 e8 e5 07 88 88 c0 db}  //weight: 1, accuracy: High
        $x_1_2 = {62 0f a8 13 f1 20 56 73 9b 88 c9 82 13 de 92 08 8a ad 88 d4 44 e4 5e bf 87 47 22 c9 db dc 95 06 cd 8f 17 97 84 a3 fd 6b cd 75 96 a0 7e 19 f0 e4 e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

