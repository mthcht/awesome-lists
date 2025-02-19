rule VirTool_Win64_Pycrad_A_2147933832_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Pycrad.A"
        threat_id = "2147933832"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Pycrad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pyramid_module" ascii //weight: 1
        $x_1_2 = "encode_encrypt_url" ascii //weight: 1
        $x_1_3 = "pyramid_pass" ascii //weight: 1
        $x_1_4 = "PROTOCOL_TLS_CLIENT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

