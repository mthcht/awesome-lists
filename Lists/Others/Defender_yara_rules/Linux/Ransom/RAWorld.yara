rule Ransom_Linux_RAWorld_A_2147946605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/RAWorld.A!MTB"
        threat_id = "2147946605"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "RAWorld"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "RA World" ascii //weight: 1
        $x_1_2 = "main.encryptFile" ascii //weight: 1
        $x_1_3 = "path/filepath.readDirNames" ascii //weight: 1
        $x_1_4 = {74 74 70 3a 2f 2f 72 61 77 6f 72 6c 64 [0-80] 2e 6f 6e 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

