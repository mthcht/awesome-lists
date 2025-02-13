rule TrojanDownloader_Win32_Kryptik_RDC_2147840145_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kryptik.RDC!MTB"
        threat_id = "2147840145"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "requireAdministrator" ascii //weight: 1
        $x_1_2 = "requestedExecutionLevel" ascii //weight: 1
        $x_2_3 = {d3 c3 0f c9 d2 dd 8b 4d ?? 02 d9 66 ?? ?? ?? ?? 3b fc 32 d3 0f 93 c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

