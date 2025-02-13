rule Trojan_Win32_Laziok_A_2147693752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Laziok.gen.A!dha"
        threat_id = "2147693752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Laziok"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&data2=xxx&HWID=" ascii //weight: 1
        $x_1_2 = "&diskhard=" ascii //weight: 1
        $x_1_3 = "&GrabData=" ascii //weight: 1
        $x_1_4 = "&memoireRAMbytes=" ascii //weight: 1
        $x_1_5 = "&parefire=" ascii //weight: 1
        $x_1_6 = "&webnavig=" ascii //weight: 1
        $x_1_7 = "414fileh0st.exe" ascii //weight: 1
        $x_1_8 = "\\admin.exe" ascii //weight: 1
        $x_2_9 = "\\azioklmpx\\" ascii //weight: 2
        $x_1_10 = "\\hzid.txt" ascii //weight: 1
        $x_1_11 = "\\jbigi.dll" ascii //weight: 1
        $x_1_12 = "\\System\\outputcrami.txt" ascii //weight: 1
        $x_1_13 = "\\value.txt" ascii //weight: 1
        $x_1_14 = "click.pack" ascii //weight: 1
        $x_1_15 = "d_elay.php" ascii //weight: 1
        $x_1_16 = "Desintall" ascii //weight: 1
        $x_1_17 = {44 6c 45 78 65 00}  //weight: 1, accuracy: High
        $x_1_18 = {44 6c 49 6e 6a 00}  //weight: 1, accuracy: High
        $x_1_19 = {44 6c 4a 61 72 00}  //weight: 1, accuracy: High
        $x_1_20 = "f_i_l_e_h_o_s_t.php" ascii //weight: 1
        $x_1_21 = "i2p/install_i2p_service_winnt.bat" ascii //weight: 1
        $x_1_22 = "i2p/set_config_dir_for_nt_service.bat" ascii //weight: 1
        $x_1_23 = "JWFwcGRhdGElAA==" ascii //weight: 1
        $x_1_24 = "killyourtv_at_mail.i2p" ascii //weight: 1
        $x_1_25 = "verif.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

