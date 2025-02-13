rule Worm_Win32_Netlip_A_2147624872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Netlip.A"
        threat_id = "2147624872"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Netlip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {43 3a 5c 43 4f 4e 46 49 47 2e 5f ?? 5f}  //weight: 10, accuracy: Low
        $x_10_2 = "Escritorio\\PUBLINet.EXE" ascii //weight: 10
        $x_1_3 = "Subject: PUBLINet" ascii //weight: 1
        $x_1_4 = "RCPT TO: <sicom_" ascii //weight: 1
        $x_1_5 = "PUBLICIDAD ELECTRONICA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

