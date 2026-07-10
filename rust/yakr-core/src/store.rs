use std::path::{Path, PathBuf};

use crate::identity::{export_public_bundle, Contact, ContactDict, Identity, PublicBundle};

pub struct FileLocalStore {
    pub root: PathBuf,
}

impl FileLocalStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn identity_path(&self) -> PathBuf {
        self.root.join("identity.json")
    }

    pub fn contacts_dir(&self) -> PathBuf {
        self.root.join("contacts")
    }

    pub fn load_identity(&self) -> Result<Option<Identity>, String> {
        if !self.identity_path().exists() {
            return Ok(None);
        }
        Identity::load(&self.identity_path()).map(Some)
    }

    pub fn save_identity(&self, identity: &Identity) -> Result<(), String> {
        identity.save(&self.identity_path()).map_err(|e| e.to_string())?;
        let bundle = export_public_bundle(identity);
        let public_path = self.root.join("public.json");
        std::fs::write(
            &public_path,
            serde_json::to_string_pretty(&bundle).unwrap(),
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn contact_path(&self, name: &str) -> PathBuf {
        self.contacts_dir().join(format!("{name}.json"))
    }

    pub fn get_contact(&self, name: &str) -> Result<Option<Contact>, String> {
        let path = self.contact_path(name);
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let dict: ContactDict = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        Contact::from_dict(&dict).map(Some)
    }

    pub fn save_contact(&self, contact: &Contact) -> Result<(), String> {
        std::fs::create_dir_all(self.contacts_dir()).map_err(|e| e.to_string())?;
        let json = serde_json::to_string_pretty(&contact.to_dict()).map_err(|e| e.to_string())?;
        std::fs::write(self.contact_path(&contact.name), json).map_err(|e| e.to_string())
    }

    pub fn list_contacts(&self) -> Result<Vec<String>, String> {
        if !self.contacts_dir().exists() {
            return Ok(vec![]);
        }
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&self.contacts_dir()).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            if entry.path().extension().and_then(|s| s.to_str()) == Some("json") {
                if let Some(stem) = entry.path().file_stem().and_then(|s| s.to_str()) {
                    names.push(stem.to_string());
                }
            }
        }
        names.sort();
        Ok(names)
    }
}
