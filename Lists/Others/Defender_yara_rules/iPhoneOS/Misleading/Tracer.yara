rule Misleading_iPhoneOS_Tracer_A_331384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:iPhoneOS/Tracer.A!xp"
        threat_id = "331384"
        type = "Misleading"
        platform = "iPhoneOS: "
        family = "Tracer"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iPhone Developer: mourad ben ayed" ascii //weight: 1
        $x_1_2 = "%s[L%d] [%@] Upload VIDEO" ascii //weight: 1
        $x_1_3 = "%s[L%d] [%@] +Begin recording" ascii //weight: 1
        $x_1_4 = "com.timecompiler.recorder" ascii //weight: 1
        $x_1_5 = "/var/mobile/Tracer/call_history.db" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

