rule Trojan_Win32_SyncAppvPublishAbuse_A_2147825890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SyncAppvPublishAbuse.A"
        threat_id = "2147825890"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SyncAppvPublishAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "AppvPublishingServer" wide //weight: 10
        $x_2_2 = ").DownloadString(" wide //weight: 2
        $x_2_3 = ").DownloadFile(" wide //weight: 2
        $x_1_4 = "Invoke-Command" wide //weight: 1
        $x_1_5 = ";IEX" wide //weight: 1
        $x_1_6 = "|IEX" wide //weight: 1
        $x_1_7 = " IEX" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SyncAppvPublishAbuse_A_2147825890_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SyncAppvPublishAbuse.A"
        threat_id = "2147825890"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SyncAppvPublishAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "AppvPublishingServer" wide //weight: 10
        $x_2_2 = "::ReadAllBytes(" wide //weight: 2
        $x_2_3 = "::ReadAllText(" wide //weight: 2
        $x_2_4 = "Get-Content " wide //weight: 2
        $x_1_5 = "Invoke-Command" wide //weight: 1
        $x_1_6 = ";IEX" wide //weight: 1
        $x_1_7 = "|IEX" wide //weight: 1
        $x_1_8 = " IEX" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

