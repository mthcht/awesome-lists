rule Trojan_AndroidOS_Autolycos_A_2147826925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Autolycos.A"
        threat_id = "2147826925"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Autolycos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NPQiBexTwGA8UeV58U06hP3SfNwXBSHAvWOtsKl30qEQk1D6dvTp43hT1U3bOi7C" ascii //weight: 1
        $x_1_2 = "Java_com_okcamera_funny_main_ui_FunnyCameraApp_initApp" ascii //weight: 1
        $x_1_3 = {ec 33 40 f9 ec 57 80 b9 ee 27 40 f9 b7 16 80 52 59 09 80 52 d1 69 6c 38 e0 1f 40 f9 f3 33 40 b9 00 c8 73 38 f3 02 31 0a 31 02 19 0a 71 02 11 2a f3 02 20 0a 00 00 19 0a 60 02 00 2a 11 00 11 4a d1 69 2c 38 ac 02 00 d0 ae 02 00 d0 b1 02 00 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

