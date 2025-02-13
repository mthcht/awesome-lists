rule Trojan_AndroidOS_Denofow_A_2147646072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Denofow.A"
        threat_id = "2147646072"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Denofow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://turbobit.net/3qijra41byed.html" ascii //weight: 1
        $x_1_2 = "endoftheworld" ascii //weight: 1
        $x_1_3 = "05212011" ascii //weight: 1
        $x_1_4 = "Cannot talk right now, the world is about to end" ascii //weight: 1
        $x_1_5 = "Jebus is way over due for a come back" ascii //weight: 1
        $x_1_6 = "Its the Raptures,praise Jebus" ascii //weight: 1
        $x_1_7 = "ZPrepare to meet thy maker, make sure to hedge your bet just in case the Muslims were right" ascii //weight: 1
        $x_1_8 = "Just saw the four horsemen of the apocalypse and man did they have the worst case of road rage" ascii //weight: 1
        $x_1_9 = "Es el fin del mundo" ascii //weight: 1
        $x_1_10 = "I am infected and alive ver 1.00" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

