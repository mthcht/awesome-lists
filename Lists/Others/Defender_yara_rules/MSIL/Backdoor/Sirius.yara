rule Backdoor_MSIL_Sirius_PA_2147981227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Sirius.PA!MTB"
        threat_id = "2147981227"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sirius"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DownloadPayload" ascii //weight: 1
        $x_1_2 = "SEED_PAYLOAD_URL" ascii //weight: 1
        $x_1_3 = "PAYLOAD_URL_ENCRYPTED_BYTES" ascii //weight: 1
        $x_4_4 = {06 07 8f 26 00 00 01 25 71 26 00 00 01 02 61 d2 81 26 00 00 01 07 17 58 0b 07 06 8e 69 32 e1}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

