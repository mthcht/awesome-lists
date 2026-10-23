rule Trojan_Win32_PWSStealer_AAB_2147980833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PWSStealer.AAB!AMTB"
        threat_id = "2147980833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PWSStealer"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "abe_probe.pdb" ascii //weight: 10
        $x_1_2 = "crates\\shadow-browser\\src\\bin\\abe_probe.rs" ascii //weight: 1
        $x_1_3 = "\\spyer\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\base64-0.22.1\\src\\engine\\general_purpose\\decode.rs" ascii //weight: 1
        $x_1_4 = "LazyLock instance has previously been poisonedlibrary\\std\\src\\sync\\lazy_lock.rs" ascii //weight: 1
        $x_1_5 = "os_crypt.app_bound_encrypted_key" ascii //weight: 1
        $x_1_6 = "&\\AppData\\Local\\Google\\Chrome\\User Data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

