rule Ransom_Win32_Darkside_XR_2147773615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Darkside.XR!MTB"
        threat_id = "2147773615"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Darkside"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "All of your files are encrypted! And your Data Leak!" ascii //weight: 1
        $x_1_2 = "But you can restore everything by purchasing a special program from us - universal decryptor" ascii //weight: 1
        $x_1_3 = {68 74 74 70 3a 2f 2f 64 61 72 6b 73 69 64 65 [0-16] 2e 6f 6e 69 6f 6e 2f}  //weight: 1, accuracy: Low
        $x_1_4 = "DO NOT MODIFY or try to RECOVER any files yourself. We WILL NOT be able to RESTORE them." ascii //weight: 1
        $x_1_5 = "We guarantee to decrypt one file for free. Go to the site and contact us" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

