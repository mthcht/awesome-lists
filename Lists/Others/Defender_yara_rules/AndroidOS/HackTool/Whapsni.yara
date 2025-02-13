rule HackTool_AndroidOS_Whapsni_A_2147787072_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/Whapsni.A!MTB"
        threat_id = "2147787072"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "Whapsni"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "whatsapp.sniffer.UPDATE_UI_CONVERSACION" ascii //weight: 1
        $x_1_2 = "WhatsAppSniffer START SPOOFING" ascii //weight: 1
        $x_1_3 = "killall arpspoof" ascii //weight: 1
        $x_1_4 = "Sniffer debug info" ascii //weight: 1
        $x_1_5 = {4c 63 6f 6d 2f 77 68 61 74 73 61 70 70 2f 73 6e 69 66 66 65 72 [0-16] 73 65 72 76 69 63 65 73 2f 41 72 70 73 70 6f 6f 66 53 65 72 76 69 63 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

