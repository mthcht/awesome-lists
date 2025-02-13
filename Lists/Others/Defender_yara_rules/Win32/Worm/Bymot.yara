rule Worm_Win32_Bymot_A_2147642581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bymot.A"
        threat_id = "2147642581"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bymot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mrd_sn" ascii //weight: 1
        $x_1_2 = "MAIL FROM: <%s>" ascii //weight: 1
        $x_1_3 = "AtmStat: aid=%d T=%d G=%d B=%d (bl=%d,nouser=%d,nomx=%d,ioerr=%d,err=%d,e_conn=%d,e_conn_rej=%d,e_intern=%d)" ascii //weight: 1
        $x_1_4 = "STATBUSY" ascii //weight: 1
        $x_1_5 = "retryip_enabled" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

