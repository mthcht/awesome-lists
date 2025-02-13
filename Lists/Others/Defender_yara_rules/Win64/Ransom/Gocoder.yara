rule Ransom_Win64_Gocoder_P_2147744704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Gocoder.P"
        threat_id = "2147744704"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Gocoder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Hello! Your all your files are encrypted and only I can decrypt them" ascii //weight: 5
        $x_1_2 = "doctor666@mail.fr" ascii //weight: 1
        $x_1_3 = "mime.percentHexUnescape" ascii //weight: 1
        $x_5_4 = "You can be a victim of fraud" ascii //weight: 5
        $x_5_5 = "Do not rename encrypted files. You may have permanent data loss" ascii //weight: 5
        $x_1_6 = "Write me if you want to return your files - I can do it very quickly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win64_Gocoder_A_2147746169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Gocoder.A!MSR"
        threat_id = "2147746169"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Gocoder"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hello! Your all your files are encrypted and only I can decrypt them" ascii //weight: 1
        $x_1_2 = "hours then your data may be lost permanently" ascii //weight: 1
        $x_1_3 = "Do not turn off or restart the NAS equipment. This will result in data loss" ascii //weight: 1
        $x_1_4 = "Do not rename the encrypted files, because of this you can lose them forever!" ascii //weight: 1
        $x_1_5 = "main.encryptfile.func1" ascii //weight: 1
        $x_1_6 = "main.makeReadmeFile.func1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

