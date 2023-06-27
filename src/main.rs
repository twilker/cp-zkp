trait DA {
    fn create(&mut self, id: &str, value: &str) -> ();
}

struct Map {
    pub map: std::collections::HashMap<String, String>
}

impl Map {
    fn new() -> Map {
        Map {
            map: std::collections::HashMap::new()
        }
    }
}

impl DA for Map {
    fn create(&mut self, id: &str, value: &str) -> () {
        self.map.insert(String::from(id), String::from(value));
    }
}

struct UseCase<'d, D> 
where D: DA + Sync + Send
{
    data_access: &'d mut D
}

impl <'d, D> UseCase<'d, D> 
where D: DA + Sync + Send
{
    fn new(data_access: &'d mut D) -> UseCase<'d, D> {
        UseCase {
            data_access
        }
    }

    async fn create(&mut self, id: &str, value: &str) -> () {
        self.data_access.create(id, value);
    }
}

#[tokio::main]
async fn main(){
    let mut da = Map::new();
    let mut use_case = UseCase::new(&mut da);
    use_case.create("1", "2").await;
    drop(use_case);
    use_case = UseCase::new(&mut da);
    use_case.create("3", "4").await;
    println!("{:?}", da.map);
}