pub struct PassiveMinecraftFingerprint {
    pub incorrect_order: bool,
    pub field_order: Option<String>,
    /// Servers shouldn't have the sample field if there are no players online.
    pub empty_sample: bool,
    /// A favicon that has the string ""
    pub empty_favicon: bool,
}
pub fn generate_passive_fingerprint(data: &str) -> eyre::Result<PassiveMinecraftFingerprint> {
    let data: serde_json::Value = serde_json::from_str(data)?;

    let protocol_version = data
        .get("version")
        .and_then(|s| s.as_object())
        .and_then(|s| s.get("protocol"))
        .and_then(|s| s.as_u64())
        .unwrap_or_default();

    let empty_favicon = data.get("favicon").map(|s| s.as_str()) == Some(Some(""));

    let mut incorrect_order = false;
    let mut field_order = None;
    let mut empty_sample = false;

    // the correct field order is description, players, version (ignore everything
    // else)

    if let Some(data) = data.as_object() {
        // mojang changed the order in 23w07a/1.19.4
        let correct_order = if matches!(protocol_version, 1073741943.. | 762..=0x40000000 ) {
            ["version", "description", "players"]
        } else {
            ["description", "players", "version"]
        };

        let keys = data
            .keys()
            .filter(|&k| correct_order.contains(&k.as_str()))
            .cloned()
            .collect::<Vec<_>>();

        let players = data.get("players").and_then(|s| s.as_object());
        let version = data.get("version").and_then(|s| s.as_object());

        let correct_players_order = ["max", "online"];
        let correct_version_order = ["name", "protocol"];

        let players_keys = players
            .map(|s| {
                s.keys()
                    .filter(|&k| correct_players_order.contains(&k.as_str()))
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let version_keys = version
            .map(|s| {
                s.keys()
                    .filter(|&k| correct_version_order.contains(&k.as_str()))
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        if keys != correct_order
            || players_keys != correct_players_order
            || version_keys != correct_version_order
        {
            incorrect_order = true;
        }

        if incorrect_order {
            let mut field_order_string = String::new();
            for (i, key) in keys.iter().enumerate() {
                field_order_string.push_str(key);
                if key == "players" && players_keys != correct_players_order {
                    field_order_string.push_str(format!("({})", players_keys.join(",")).as_str());
                } else if key == "version" && version_keys != correct_version_order {
                    field_order_string.push_str(format!("({})", version_keys.join(",")).as_str());
                }
                if i != keys.len() - 1 {
                    field_order_string.push(',');
                }
            }
            field_order = Some(field_order_string);
        }

        if let Some(players) = data.get("players").and_then(|s| s.as_object())
            && let Some(sample) = players.get("sample").and_then(|s| s.as_array())
            && sample.is_empty()
        {
            empty_sample = true;
        }
    }

    Ok(PassiveMinecraftFingerprint {
        incorrect_order,
        field_order,
        empty_sample,
        empty_favicon,
    })
}
