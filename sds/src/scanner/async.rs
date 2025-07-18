// use futures::executor::block_on;
// use futures::FutureExt;
// use std::future::Future;
//
// // A future that may be known to resolve immediately
// pub struct MaybeAsync<F: Future> {
//     will_resolve_immediately: bool,
//     fut: F,
// }
//
// impl<F: Future> MaybeAsync<F> {
//     pub fn new(will_resolve_immediately: bool, fut: F) -> MaybeAsync<F> {
//         MaybeAsync {
//             will_resolve_immediately,
//             fut,
//         }
//     }
//
//     pub fn will_resolve_immediately(&self) -> bool {
//         self.will_resolve_immediately
//     }
//
//     /// Blocks the current thread until the value is available.
//     pub fn blocking_get(self) -> F::Output {
//         block_on(self.fut)
//     }
//
//     pub async fn async_get(self) -> F::Output {
//         self.fut.await
//     }
//
//     pub fn then<A>(
//         self,
//         will_resolve_immediately: bool,
//         f: impl FnOnce(F::Output) -> A,
//     ) -> MaybeAsync<impl Future<Output = <A as Future>::Output>>
//     where
//         A: Future,
//     {
//         MaybeAsync {
//             will_resolve_immediately: self.will_resolve_immediately && will_resolve_immediately,
//             fut: self.fut.then(async |x| (f)(x).await),
//         }
//     }
// }
