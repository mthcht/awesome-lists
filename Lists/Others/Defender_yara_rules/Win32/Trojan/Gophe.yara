rule Trojan_Win32_Gophe_A_2147691490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gophe.A"
        threat_id = "2147691490"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gophe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "additional_emails" ascii //weight: 1
        $x_1_2 = "attach_data_base64" ascii //weight: 1
        $x_2_3 = "Bitness" ascii //weight: 2
        $x_1_4 = "client_connection_id" ascii //weight: 1
        $x_1_5 = "download_url" ascii //weight: 1
        $x_1_6 = "file_data" ascii //weight: 1
        $x_1_7 = "message_attach" ascii //weight: 1
        $x_1_8 = "Outlook-Additional-Address-Total" ascii //weight: 1
        $x_1_9 = "Outlook-Address-Total" ascii //weight: 1
        $x_1_10 = "Outlook-Messages-Created" ascii //weight: 1
        $x_1_11 = "send_to_all" ascii //weight: 1
        $x_3_12 = {8d 70 08 8d 64 24 00 8b f9 c1 ef 1e 33 cf 69 c9 ?? ?? ?? ?? 03 ca 89 0e 42 83 c6 04 81 fa 70 02 00 00 7c e3}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

