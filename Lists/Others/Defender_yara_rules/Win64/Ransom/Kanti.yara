rule Ransom_Win64_Kanti_AK_2147851172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Kanti.AK!MTB"
        threat_id = "2147851172"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Kanti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ATTENTION, TAKE THIS SERIOUSLY!" ascii //weight: 1
        $x_1_2 = "All your important files have been locked" ascii //weight: 1
        $x_1_3 = "Do not modify, rename or delete any files" ascii //weight: 1
        $x_1_4 = "Do not shut down or restart your computer" ascii //weight: 1
        $x_1_5 = "Do not attempt to unlock files using third-party software" ascii //weight: 1
        $x_1_6 = "You need to contact us immediately to unlock all your files" ascii //weight: 1
        $x_1_7 = "If you do not contact us in the next few days, you will lose all your files" ascii //weight: 1
        $x_1_8 = "CONTACT US THROUGH EMAIL: kanti@dnmx.com" ascii //weight: 1
        $x_1_9 = "Cooperating with us will guarantee that all your files will be recovered completely" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

