extern crate nonblock_logger;
extern crate serde;
extern crate sqlx;
extern crate validator;

use ntex::{web, web::App, web::HttpServer};
use ntex_cors::Cors;
//use actix_cors::Cors;
//use actix_web::{middleware, web, App, HttpServer};
use num_cpus;

// pub mod accounts;
pub mod config;
pub mod middlewares;
pub mod state;
pub mod users;
pub mod utils;

use config::{Config, Opts};

#[ntex::main]
async fn main() -> std::io::Result<()> {
    Config::show();
    let (_handle, opt) = Opts::parse_from_args();
    let state = Config::parse_from_file(&opt.config).into_state().await;
    let state2 = state.clone();
    let apiv1 = "/api/v1";

    HttpServer::new(move || {
        App::new()
            .wrap(
                Cors::new()
                    .allowed_origin("http://localhost:5173")
                    .supports_credentials()
                    .max_age(3600)
                    .finish()
            )
            .state(state.clone())
            .wrap(web::middleware::Logger::default())
            .wrap(web::middleware::Compress::default())
            .service(web::scope(apiv1).configure(users::routes::init))
    })
    .workers(num_cpus::get())
    .keep_alive(300)
    .bind(&state2.config.listen)?
    .run()
    .await
}
