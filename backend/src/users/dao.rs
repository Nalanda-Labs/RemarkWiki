use async_trait::async_trait;
use nonblock_logger::info;
use sqlx::{Error, Row};
use uuid::Uuid;

use super::users::*;
use crate::state::AppStateRaw;

#[async_trait]
pub trait IUser: std::ops::Deref<Target = AppStateRaw> {
    async fn user_query(&self, who: &str) -> sqlx::Result<User>;
    async fn users(
        &self,
        sort_by: &str,
        last_record: &str,
        ascending: bool,
    ) -> sqlx::Result<(Vec<User>, u64)>;
    async fn email_exists(&self, email: &str) -> sqlx::Result<bool>;
    async fn username_exists(&self, username: &str) -> sqlx::Result<bool>;
    async fn create_user(&self, req: &CreateUserRequest) -> sqlx::Result<String>;
    async fn edit_user(&self, req: &EditUserRequest, id: &Uuid) -> sqlx::Result<String>;
    async fn get_user(&self, id: Uuid) -> sqlx::Result<UserResponse>;
}

#[cfg(any(feature = "postgres"))]
#[async_trait]
impl IUser for &AppStateRaw {
    async fn user_query(&self, email: &str) -> sqlx::Result<User> {
        let user = sqlx::query_as!(
            User,
            r#"SELECT id, first_name, last_name, username, email, password_hash, created_date,
            modified_date, is_admin, status
            FROM users
            where email = $1 and deleted=false"#,
            email
        )
        .fetch_optional(&self.sql)
        .await?;

        let user = match user {
            Some(user) => user,
            None => {
                return Err(Error::RowNotFound);
            }
        };

        info!("User found   ");
        Ok(user)
    }

    async fn users(
        &self,
        sort_by: &str,
        last_record: &str,
        ascending: bool,
    ) -> sqlx::Result<(Vec<User>, u64)> {
        let res = sqlx::query!(
            r#"
                select count(1) from users where deleted=false;
            "#,
        )
        .fetch_one(&self.sql)
        .await?;

        let count = match res.count {
            Some(c) => c as u64,
            None => 0 as u64,
        };

        let mut sort_by_col = sort_by;

        if sort_by == "" {
            sort_by_col = "first_name";
        }

        let q: String;

        if ascending {
            q = format!(
                "SELECT id, first_name, last_name, username, email, password_hash, created_date,
                modified_date, is_admin, status,
                FROM users where deleted=false and {sort_by_col} > '{last_record}' order by {sort_by_col} limit {results_per_page}",
                sort_by_col=sort_by_col, last_record=last_record, results_per_page=self.config.results_per_page
            );
        } else {
            q = format!(
                "SELECT id, first_name, last_name, username, email, password_hash, created_date,
                modified_date, is_admin, status
                FROM users where deleted=false and {sort_by_col} < '{last_record}' order by {sort_by_col} DESC limit {results_per_page}",
                sort_by_col=sort_by_col, last_record=last_record, results_per_page=self.config.results_per_page
            );
        }

        let res1 = sqlx::query(&q).fetch_all(&self.sql).await?;

        let mut users: Vec<User> = Vec::new();
        for r in res1 {
            let user: User = User {
                id: r.try_get("id")?,
                first_name: r.try_get("first_name")?,
                last_name: r.try_get("last_name")?,
                username: r.try_get("username")?,
                email: r.try_get("email")?,
                password_hash: r.try_get("password_hash")?,
                created_date: r.try_get("created_date")?,
                modified_date: r.try_get("modified_date")?,
                is_admin: r.try_get("is_admin")?,
                status: r.try_get("status")?,
            };
            users.push(user);
        }

        Ok((users, count))
    }

    async fn email_exists(&self, email: &str) -> sqlx::Result<bool> {
        let row = sqlx::query!(
            r#"
            SELECT email from users where email=$1
            "#,
            email
        )
        .fetch_optional(&self.sql)
        .await?;

        let email = match row {
            Some(s) => s.email,
            None => "".to_owned(),
        };

        if email != "" {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn username_exists(&self, username: &str) -> sqlx::Result<bool> {
        let row = sqlx::query!(
            r#"
            SELECT username from users where username=$1
            "#,
            username
        )
        .fetch_optional(&self.sql)
        .await?;

        let username = match row {
            Some(s) => s.username,
            None => "".to_owned(),
        };

        if username != "" {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn create_user(&self, req: &CreateUserRequest) -> sqlx::Result<String> {
        let mut tx = self.sql.begin().await?;
        let id = uuid::Uuid::new_v4();
        let password_hash = passhash(&req.password);

        sqlx::query!(
            r#"
                INSERT into users(id, email, password_hash, first_name, last_name, username,
                is_admin, status)
                VALUES($1, $2, $3, $4, $5, $6, $7, $8)
                "#,
            id,
            &req.email,
            &password_hash,
            &req.first_name,
            &req.last_name,
            &req.username,
            &req.is_admin,
            &req.status
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        return Ok(id.to_string());
    }

    async fn edit_user(&self, req: &EditUserRequest, id: &Uuid) -> sqlx::Result<String> {
        let mut tx = self.sql.begin().await?;

        sqlx::query!(
            r#"
                UPDATE users set email=$2, first_name=$3, last_name=$4, username=$5,
                is_admin=$6, status=$7 where id=$1
                "#,
            id,
            &req.email,
            &req.first_name,
            &req.last_name,
            &req.username,
            &req.is_admin,
            &req.status
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        return Ok(id.to_string());
    }
    async fn get_user(&self, id: Uuid) -> sqlx::Result<UserResponse> {
        let u = sqlx::query_as!(
            UserResponse,
            r#"
            SELECT email, username, first_name, last_name, is_admin, status
            from users where id=$1
            "#,
            id
        )
        .fetch_one(&self.sql)
        .await?;

        Ok(u)
    }
}
