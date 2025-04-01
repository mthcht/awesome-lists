rule Trojan_Win32_ProcessDiscovery_A_2147764300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ProcessDiscovery.A"
        threat_id = "2147764300"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ProcessDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "qprocess" wide //weight: 1
        $x_1_2 = {71 00 75 00 65 00 72 00 79 00 [0-16] 70 00 72 00 6f 00 63 00 65 00 73 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ProcessDiscovery_C_2147766438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ProcessDiscovery.C"
        threat_id = "2147766438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ProcessDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tasklist" wide //weight: 1
        $n_1_2 = "/svc" wide //weight: -1
        $n_1_3 = "-svc" wide //weight: -1
        $n_1_4 = "devenv.exe" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_ProcessDiscovery_B_2147768113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ProcessDiscovery.B!tlist"
        threat_id = "2147768113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ProcessDiscovery"
        severity = "Critical"
        info = "tlist: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 00 61 00 73 00 6b 00 6c 00 69 00 73 00 74 00 [0-16] 2f 00 73 00 76 00 63 00}  //weight: 1, accuracy: Low
        $n_10_2 = "IP Desktop Softphone" wide //weight: -10
        $n_10_3 = "MyNOEPhoneIPDesktop.exe" wide //weight: -10
        $n_10_4 = "Nintendo.ProjectPortal.exe" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_ProcessDiscovery_SH_2147937551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ProcessDiscovery.SH"
        threat_id = "2147937551"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ProcessDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& tasklist /m &" ascii //weight: 1
        $x_1_2 = "& tasklist /svc &" ascii //weight: 1
        $x_1_3 = "& tasklist /v &" ascii //weight: 1
        $n_10_4 = "& echo ####tasklist####" ascii //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

