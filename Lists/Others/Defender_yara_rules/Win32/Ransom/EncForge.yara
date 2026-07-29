rule Ransom_Win32_EncForge_MKV_2147974692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/EncForge.MKV!MTB"
        threat_id = "2147974692"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "EncForge"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "/tmp/.sk/lockd" wide //weight: 5
        $x_4_2 = "&& chmod +x" wide //weight: 4
        $x_3_3 = "curl -m30" wide //weight: 3
        $x_2_4 = "http://" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

