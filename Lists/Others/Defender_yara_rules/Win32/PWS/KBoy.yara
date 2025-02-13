rule PWS_Win32_KBoy_A_2147683158_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/KBoy.A"
        threat_id = "2147683158"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "KBoy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Proxy 201" ascii //weight: 1
        $x_1_2 = "IJUDHSDJFKJDE" ascii //weight: 1
        $x_1_3 = "Microsoft device and Drivers Update" ascii //weight: 1
        $x_1_4 = "$sysinfo$" ascii //weight: 1
        $x_1_5 = "$shell$" ascii //weight: 1
        $x_1_6 = "$fileUpload$" ascii //weight: 1
        $x_1_7 = {43 52 45 44 52 49 56 45 52 [0-1] 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_8 = " website = %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

