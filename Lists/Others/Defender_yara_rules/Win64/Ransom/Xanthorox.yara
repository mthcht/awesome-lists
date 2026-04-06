rule Ransom_Win64_Xanthorox_AMTB_2147966342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Xanthorox!AMTB"
        threat_id = "2147966342"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Xanthorox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your files have been encrypted by Xanthorox AI based Ransomware" ascii //weight: 1
        $x_1_2 = "... PASTE YOUR FULL RANSOM NOTE HERE ... {VICTIM_ID} ..." ascii //weight: 1
        $x_1_3 = "XanthoroxInstanceMutex_v3_Final_Unique" ascii //weight: 1
        $x_1_4 = "C:\\TEMP\\xanthorox_log.txt" ascii //weight: 1
        $x_1_5 = "XANTHOROX V3 HIT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

