rule Ransom_Win32_Cryck_2147740928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cryck"
        threat_id = "2147740928"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryck"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your computer has been attacked by virus-encoder" ascii //weight: 1
        $x_1_2 = "All your files are now encrypted using cry" ascii //weight: 1
        $x_1_3 = "TO GET YOUR DECODER AND THE ORIGINAL KEY TO DECRYPT YOUR" ascii //weight: 1
        $x_1_4 = "boooam@cock.li" ascii //weight: 1
        $x_1_5 = "It is in your interest to respond as soon as possible to ensure the restoration of your files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

