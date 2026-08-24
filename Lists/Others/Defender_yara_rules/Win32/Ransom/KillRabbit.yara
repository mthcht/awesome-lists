rule Ransom_Win32_KillRabbit_PA_2147976852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/KillRabbit.PA!MTB"
        threat_id = "2147976852"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "KillRabbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "_ENCRYPTFILE ( $FILE , $FILE & \".killrabbit" ascii //weight: 3
        $x_1_2 = "= \"http://rektware16.temp.swtest.ru/" ascii //weight: 1
        $x_1_3 = "it seems the rabbit encrypted all of your files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

