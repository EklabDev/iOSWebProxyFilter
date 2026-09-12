import Foundation
import BackgroundTasks

enum RetentionScheduler {
    static func register() {
        BGTaskScheduler.shared.register(
            forTaskWithIdentifier: AppConstants.retentionTaskId,
            using: nil
        ) { task in
            handle(task as? BGProcessingTask)
        }
    }

    static func pruneNow() {
        let db = Database()
        let store = ConnectionsStore(db: db)
        store.prune(cutoff: RetentionPolicy().cutoffMillis())
    }

    static func schedule() {
        let request = BGProcessingTaskRequest(identifier: AppConstants.retentionTaskId)
        request.requiresNetworkConnectivity = false
        request.requiresExternalPower = false
        request.earliestBeginDate = Date(timeIntervalSinceNow: 24 * 60 * 60)
        try? BGTaskScheduler.shared.submit(request)
    }

    private static func handle(_ task: BGProcessingTask?) {
        guard let task else { return }
        schedule()
        task.expirationHandler = {}
        pruneNow()
        task.setTaskCompleted(success: true)
    }
}
