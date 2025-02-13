rule Ransom_Win32_DarkTrace_MA_2147848095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DarkTrace.MA!MTB"
        threat_id = "2147848095"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkTrace"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "vssadmin Delete Shadows /All /Quiet" ascii //weight: 3
        $x_3_2 = "Your data are stolen and encrypted" ascii //weight: 3
        $x_3_3 = "The data will be published on TOR website if you do not pay the ransom " ascii //weight: 3
        $x_3_4 = "We are not a politically motivated group and we do not need anything other than your money" ascii //weight: 3
        $x_3_5 = "If you pay, we will provide you the programs for decryption and we will delete your data" ascii //weight: 3
        $x_3_6 = "kill_processes" ascii //weight: 3
        $x_3_7 = "delete_eventlogs" ascii //weight: 3
        $x_1_8 = "Mail (OnionMail) Support: darkrace@onionmail.org" ascii //weight: 1
        $x_1_9 = "DarkRace ransomware" ascii //weight: 1
        $x_1_10 = "LockBit 3.0 the world's fastest ransomware" ascii //weight: 1
        $x_1_11 = "Mail (OnionMail) Support: lockdark@onionmail.org" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_DarkTrace_MKV_2147848248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DarkTrace.MKV!MTB"
        threat_id = "2147848248"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkTrace"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 c1 e8 ?? 88 45 fa 8d 45 b0 50 8d 45 ?? c1 e9 18 50 ff 75 08 88 4d fb ff d2 8b 45 18 83 c4 0c 8b 55 0c 8d 0c 18 8a 44 35 ?? 43 30 01 8b 45 18 83 ef 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

