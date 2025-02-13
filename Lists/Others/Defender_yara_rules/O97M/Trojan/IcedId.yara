rule Trojan_O97M_IcedId_IC_2147771306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/IcedId.IC!MTB"
        threat_id = "2147771306"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"2e6a6f696e282222293b0d0a76617220614d5144466f203d2022633a5c5c70726f6772616d646174615c5c61656e594f2e706466223b0d0a0d0a77696e646f77\"" ascii //weight: 1
        $x_1_2 = "2e737461747573203d20323030205468656e0d0a0953657420615a653449203d204372656174654f626a656374282261646f64622e73747265616d22290d0a09" ascii //weight: 1
        $x_1_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-10] 29 2e 72 75 6e 20 28 [0-10] 20 26 20 22 20 22 20 26 20 [0-10] 29}  //weight: 1, accuracy: Low
        $x_1_4 = "= Des(\"7261655845737561655845736e61655845736461655845736c61655845736c61655845733361655845733261655845732e616558457365616558457378616558457365616558457320616558457375" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

