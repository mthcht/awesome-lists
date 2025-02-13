rule TrojanDownloader_Win64_GoDown_loader_S1_2147924287_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/GoDown-loader.S1"
        threat_id = "2147924287"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "GoDown-loader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.create_new_file" ascii //weight: 1
        $x_1_2 = "main.write_new_file" ascii //weight: 1
        $x_1_3 = "main.aesDecrypt_obf" ascii //weight: 1
        $x_1_4 = "main.(*Exec).get_command_context" ascii //weight: 1
        $x_1_5 = "/loader/temp/temp.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

