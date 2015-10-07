extern crate keepass;
extern crate rpassword;

use keepass::kpdb::v1error::V1KpdbError;
use keepass::kpdb::v1kpdb::V1Kpdb;

use rpassword::read_password;

use std::env;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        println!("Usage {:} KDBPATH [ENTRYNAME|l] ", args[0]);
    } else {
        let password = read_password().unwrap();
        let db = args[1].clone();
        let option = args[2].clone();
        let kdb = getDatabase(db, password).ok().expect("Failed to open database");
        if option == "l" {
            listEntries(kdb);
        } else {
            printPassword(kdb, option);
        }
    }
}

fn listEntries(kdb: V1Kpdb) -> Result<(), V1KpdbError> {
    for entry in kdb.entries {
        if entry.borrow().title != "Meta-Info".to_string() {
            println!("{:}", entry.borrow().title);
        }
    }
    return Ok(())
}

fn printPassword(kdb: V1Kpdb, entryName: String) -> Result<(), V1KpdbError> {
    for entry in kdb.entries {
        if entry.borrow().title == entryName {
            entry.borrow_mut().password.unlock();
            print!("{:}", entry.borrow().password.string);
            return Ok(())
        }
    }
    return Ok(())
}

fn getDatabase(db: String, password: String) -> Result<V1Kpdb, V1KpdbError> {
    let mut result = try!(V1Kpdb::new(db, Some(password), None));
    try!(result.load());
    return Ok(result);
}
