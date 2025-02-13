rule Trojan_AndroidOS_Looter_A_2147745180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Looter.A!MTB"
        threat_id = "2147745180"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Looter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SuperSU_len" ascii //weight: 1
        $x_1_2 = "shell_unroot" ascii //weight: 1
        $x_1_3 = "shell_nosyswrite" ascii //weight: 1
        $x_1_4 = "Java_com_alephzain_framaroot_FramaActivity_Launch" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

