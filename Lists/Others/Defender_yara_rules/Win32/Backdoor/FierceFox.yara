rule Backdoor_Win32_FierceFox_A_2147926602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/FierceFox.A!dha"
        threat_id = "2147926602"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "FierceFox"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "113060055043041039057057039035038042047045035039039058041035055039046038035038038039038043055040045044057041059115" ascii //weight: 1
        $x_1_2 = "089099090036091110091022037089022050111101107104022089101099099087100090052" ascii //weight: 1
        $x_1_3 = "109091112037055093091100106037075102073098" ascii //weight: 1
        $x_1_4 = "037109091112037055093091100106037075102057094090" ascii //weight: 1
        $x_1_5 = "037109091112037055093091100106037075102057099090" ascii //weight: 1
        $x_1_6 = "037109091112037055093091100106037063100105067089094" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

